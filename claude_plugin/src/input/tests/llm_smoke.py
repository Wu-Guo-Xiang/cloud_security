"""DeepSeek v4-flash 本地部署 - 连通性烟雾测试。

本脚本 *不* 接入识别管线，只验证 HTTP 通路与响应解析。
通过后再写正式的 detectors/llm_detector.py。

用法（任一）：
    # 1. 命令行参数（最直接）
    py tests/llm_smoke.py --endpoint http://10.x.x.x:port/v1 --model deepseek-v4-flash

    # 2. 环境变量
    set DEEPSEEK_ENDPOINT=http://10.x.x.x:port/v1
    set DEEPSEEK_MODEL=deepseek-v4-flash
    py tests/llm_smoke.py

    # 3. 留空跑（仅打印请求模板，不发请求）
    py tests/llm_smoke.py --dry-run

检查项：
  [1] /v1/models 能列出模型（确认端点活）
  [2] /v1/chat/completions 单轮问答返回 200 + 合法 JSON
  [3] 结构化输出（response_format=json_object）回得是合法 JSON
  [4] 简单 NER 任务能输出预期格式（命名实体抽取的最小用例）
  [5] 记录首字节延迟与总耗时，给后续 Hook 超时设定参考
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# --- 配置 ------------------------------------------------------------

@dataclass
class LLMConfig:
    endpoint: str  # e.g. http://host:port/v1
    model: str
    api_key: str = ""           # 无鉴权时留空
    timeout_seconds: float = 10.0


def _load_config() -> tuple[LLMConfig, bool]:
    """读取命令行 / 环境变量 / 默认值。返回 (config, dry_run)。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default=os.environ.get("DEEPSEEK_ENDPOINT", ""))
    parser.add_argument("--model",    default=os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash"))
    parser.add_argument("--api-key",  default=os.environ.get("DEEPSEEK_API_KEY", ""))
    parser.add_argument("--timeout",  type=float, default=10.0)
    parser.add_argument("--dry-run",  action="store_true",
                        help="不发请求，只打印请求模板，用于核对结构")
    args = parser.parse_args()

    cfg = LLMConfig(
        endpoint=args.endpoint.rstrip("/"),
        model=args.model,
        api_key=args.api_key,
        timeout_seconds=args.timeout,
    )
    return cfg, args.dry_run


# --- HTTP --------------------------------------------------------------

def _post_json(url: str, payload: dict, headers: dict, timeout: float) -> tuple[int, dict, float]:
    """返回 (status_code, parsed_json_or_text, elapsed_seconds)。"""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
    elapsed = time.perf_counter() - started

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"_raw": raw[:500]}
    return status, parsed, elapsed


def _get_json(url: str, headers: dict, timeout: float) -> tuple[int, dict, float]:
    req = urllib.request.Request(url, method="GET")
    for k, v in headers.items():
        req.add_header(k, v)

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
    elapsed = time.perf_counter() - started

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"_raw": raw[:500]}
    return status, parsed, elapsed


def _headers(cfg: LLMConfig) -> dict:
    h = {}
    if cfg.api_key:
        h["Authorization"] = f"Bearer {cfg.api_key}"
    return h


# --- 用例 -------------------------------------------------------------

def case_list_models(cfg: LLMConfig) -> tuple[bool, str]:
    url = f"{cfg.endpoint}/models"
    status, data, elapsed = _get_json(url, _headers(cfg), cfg.timeout_seconds)
    if status != 200:
        return False, f"HTTP {status}, body={str(data)[:200]} ({elapsed*1000:.0f}ms)"
    items = data.get("data") if isinstance(data, dict) else None
    if not items:
        return False, f"响应缺少 data 字段或为空：{str(data)[:200]}"
    names = [it.get("id") for it in items if isinstance(it, dict)]
    hit = cfg.model in names
    return hit, (
        f"列出 {len(names)} 个模型（{elapsed*1000:.0f}ms）"
        f"{'，目标模型在列' if hit else f'，目标模型 {cfg.model} 不在列：{names[:5]}'}"
    )


def case_simple_chat(cfg: LLMConfig) -> tuple[bool, str]:
    url = f"{cfg.endpoint}/chat/completions"
    payload = {
        "model": cfg.model,
        "messages": [{"role": "user", "content": "请仅回复一个汉字：好"}],
        "temperature": 0.0,
        "max_tokens": 16,
    }
    status, data, elapsed = _post_json(url, payload, _headers(cfg), cfg.timeout_seconds)
    if status != 200:
        return False, f"HTTP {status}, body={str(data)[:200]} ({elapsed*1000:.0f}ms)"

    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return False, f"响应结构异常：{str(data)[:200]}"
    return True, f"耗时 {elapsed*1000:.0f}ms，回复：{content!r}"


def case_json_mode(cfg: LLMConfig) -> tuple[bool, str]:
    """验证 response_format=json_object 是否生效（NER 任务的前提）。"""
    url = f"{cfg.endpoint}/chat/completions"
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": "你只输出合法 JSON。"},
            {"role": "user", "content": '返回 {"ok": true}'},
        ],
        "temperature": 0.0,
        "max_tokens": 32,
        "response_format": {"type": "json_object"},
    }
    status, data, elapsed = _post_json(url, payload, _headers(cfg), cfg.timeout_seconds)
    if status != 200:
        return False, f"HTTP {status} ({elapsed*1000:.0f}ms) - body={str(data)[:200]}"
    try:
        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as e:
        return False, f"{type(e).__name__}: {e}; raw={str(data)[:200]}"
    return parsed.get("ok") is True, f"JSON 模式 OK，耗时 {elapsed*1000:.0f}ms，content={content}"


def case_ner_demo(cfg: LLMConfig) -> tuple[bool, str]:
    """最小可行的 NER 任务：让模型从中文文本里抽公司/人名。

    这是 detectors/llm_detector.py 将来要用的 prompt 骨架。
    """
    url = f"{cfg.endpoint}/chat/completions"
    text = "腾讯科技与阿里巴巴签订协议，由张三对接，金额 38 万元。"
    sys_prompt = (
        "你是敏感实体识别器。从用户文本中识别实体，仅输出 JSON 数组，"
        "每项 {\"text\": 原文片段, \"type\": 类型}。"
        "类型枚举：COMPANY / PERSON / MONEY / DATE / LOCATION / PRODUCT。"
        "禁止解释、禁止改写文本。"
    )
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user",   "content": text},
        ],
        "temperature": 0.0,
        "max_tokens": 256,
        "response_format": {"type": "json_object"},
    }
    status, data, elapsed = _post_json(url, payload, _headers(cfg), cfg.timeout_seconds)
    if status != 200:
        return False, f"HTTP {status} ({elapsed*1000:.0f}ms)"
    try:
        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return False, f"解析失败 {type(e).__name__}: {e}; content={data}"

    # 兼容两种形态：直接数组 / {entities: [...]}
    items = parsed if isinstance(parsed, list) else parsed.get("entities") or parsed.get("data") or []
    types_hit = {it.get("type") for it in items if isinstance(it, dict)}
    expect_any = {"COMPANY", "PERSON"}
    ok = bool(expect_any & types_hit)
    return ok, (
        f"耗时 {elapsed*1000:.0f}ms，识别 {len(items)} 个实体，类型集合={types_hit}"
        f"{'' if ok else '（未命中 COMPANY/PERSON，需调 prompt）'}"
    )


# --- main -------------------------------------------------------------

def _print_dry_run(cfg: LLMConfig) -> None:
    print("=== Dry-run：不发请求，仅打印请求模板 ===")
    print(f"endpoint = {cfg.endpoint or '<未填>'}")
    print(f"model    = {cfg.model}")
    print(f"api_key  = {'<已设置>' if cfg.api_key else '<空>'}")
    print()
    print("请求 A: GET  {endpoint}/models")
    print("请求 B: POST {endpoint}/chat/completions")
    print(json.dumps({
        "model": cfg.model,
        "messages": [{"role": "user", "content": "..."}],
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
    }, ensure_ascii=False, indent=2))


def main() -> int:
    cfg, dry_run = _load_config()

    if dry_run or not cfg.endpoint:
        _print_dry_run(cfg)
        if not cfg.endpoint:
            print("\n提示：未提供 --endpoint，跳过实际探测。")
            print("      获取本地 DeepSeek 接入地址后，用以下任一方式重跑：")
            print("        py tests/llm_smoke.py --endpoint http://x.x.x.x:port/v1")
            print("        set DEEPSEEK_ENDPOINT=http://x.x.x.x:port/v1 && py tests/llm_smoke.py")
        return 0

    print(f"目标 endpoint: {cfg.endpoint}")
    print(f"目标 model:    {cfg.model}")
    print(f"鉴权:          {'Bearer ***' if cfg.api_key else '无'}")
    print(f"超时:          {cfg.timeout_seconds}s")
    print()

    cases = [
        ("[1] /models 端点活跃",       case_list_models),
        ("[2] /chat/completions 单轮", case_simple_chat),
        ("[3] response_format=json",   case_json_mode),
        ("[4] NER demo（COMPANY/PERSON）", case_ner_demo),
    ]

    passed = failed = 0
    for label, fn in cases:
        try:
            ok, msg = fn(cfg)
        except Exception as e:
            ok, msg = False, f"{type(e).__name__}: {e}"
        flag = "OK  " if ok else "FAIL"
        print(f"[{flag}] {label} :: {msg}")
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\n用例总数: {len(cases)} | 通过: {passed} | 失败: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
