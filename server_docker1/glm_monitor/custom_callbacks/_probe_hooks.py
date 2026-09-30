"""LiteLLM hook 机制查证脚本 (只读, 不改任何状态, 不发请求)。
在 124 上: /home/app/litellm-env/bin/python /tmp/_probe_litellm_hooks.py
"""
import inspect, json

print("=" * 60)
print("1. litellm 版本")
print("=" * 60)
import litellm
print("  version:", getattr(litellm, "__version__", "?"))
print("  file:", litellm.__file__)

print()
print("=" * 60)
print("2. CustomLogger 的 hook 签名 (重点看 async_pre_call_hook)")
print("=" * 60)
try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:
    try:
        from litellm.proxy.loggers import CustomLogger
    except ImportError as e:
        CustomLogger = None
        print("  import 失败:", e)

if CustomLogger:
    for name in ["async_pre_call_hook", "async_log_success_event",
                 "async_log_failure_event", "async_logging_hook"]:
        fn = getattr(CustomLogger, name, None)
        if fn:
            try:
                sig = inspect.signature(fn)
                print(f"  {name}{sig}")
            except (ValueError, TypeError) as e:
                print(f"  {name}: 签名解析失败 {e}")
            # 看返回类型注解
            ret = getattr(fn, "__annotations__", {}).get("return", "?")
            print(f"    -> return annotation: {ret}")
        else:
            print(f"  {name}: 不存在")

print()
print("=" * 60)
print("3. async_pre_call_hook 源码 (看返回值约定: return None vs Response)")
print("=" * 60)
if CustomLogger:
    fn = getattr(CustomLogger, "async_pre_call_hook", None)
    if fn:
        try:
            src = inspect.getsource(fn)
            print(src[:1200])
        except Exception as e:
            print("  获取源码失败:", e)

print()
print("=" * 60)
print("4. proxy 如何调用 pre_call_hook (看 return 值怎么用)")
print("=" * 60)
# 在 litellm.proxy 里搜 pre_call_hook 的调用处
import os, glob
litellm_dir = os.path.dirname(litellm.__file__)
proxy_dir = os.path.join(litellm_dir, "proxy")
hits = []
if os.path.isdir(proxy_dir):
    for pyf in glob.glob(os.path.join(proxy_dir, "**", "*.py"), recursive=True):
        try:
            txt = open(pyf, encoding="utf-8", errors="replace").read()
            if "pre_call_hook" in txt and "async def" not in txt.split("pre_call_hook")[0][-200:]:
                # 找调用 pre_call_hook 的行
                for i, line in enumerate(txt.splitlines(), 1):
                    if "pre_call_hook" in line and "def " not in line:
                        rel = os.path.relpath(pyf, litellm_dir)
                        hits.append(f"  {rel}:{i}: {line.strip()[:90]}")
        except Exception:
            pass
for h in hits[:15]:
    print(h)
if not hits:
    print("  (未找到调用处, 可能函数名不同)")

print()
print("=" * 60)
print("5. data dict 里有没有 client IP? (看 proxy 请求处理)")
print("=" * 60)
# 搜 requester_ip / client_ip / proxy_server_request
for kw in ["requester_ip", "client_ip", "proxy_server_request", "x-forwarded-for"]:
    found = []
    for pyf in glob.glob(os.path.join(litellm_dir, "**", "*.py"), recursive=True):
        try:
            txt = open(pyf, encoding="utf-8", errors="replace").read()
            if kw in txt:
                rel = os.path.relpath(pyf, litellm_dir)
                for i, line in enumerate(txt.splitlines(), 1):
                    if kw in line:
                        found.append(f"  {rel}:{i}: {line.strip()[:90]}")
                        break
        except Exception:
            pass
    print(f"  [{kw}] 命中 {len(found)} 处:")
    for f in found[:4]:
        print(f)

print()
print("=" * 60)
print("6. callbacks 注册机制 (class vs instance)")
print("=" * 60)
# 搜 litellm_settings.callbacks 的解析逻辑
for kw in ["litellm.callbacks", "callbacks =", "instantiate"]:
    found = []
    for pyf in glob.glob(os.path.join(litellm_dir, "**", "*.py"), recursive=True):
        try:
            txt = open(pyf, encoding="utf-8", errors="replace").read()
            if kw in txt:
                rel = os.path.relpath(pyf, litellm_dir)
                for i, line in enumerate(txt.splitlines(), 1):
                    if kw in line:
                        found.append(f"  {rel}:{i}: {line.strip()[:90]}")
        except Exception:
            pass
    print(f"  [{kw}] {len(found)} 处:")
    for f in found[:3]:
        print(f)

print()
print("查证完成。把以上全部输出贴回。")
