"""LiteLLM 回调: 请求到达/结束时把「在途信息」推送到 GLM 监控。

目的:
  vLLM 的 /metrics 只知道"有几个请求在跑", 不知道是谁、上下文多大;
  LiteLLM 的 spend logs 要等请求结束才落库, 看不到"正在跑"的那条。
  本回调挂 LiteLLM 的 pre_call 钩子 —— 请求一到达就推送
  {人名, IP, 模型, 估算输入 token, request_id}, 结束时推 finish 含真实 token。
  这样监控页能实时显示"谁正在跑 / 输入多大", 不用等跑完。

部署 (LiteLLM 机器 192.168.3.124, systemd + venv 直跑):
  1. 把整个 custom_callbacks/ 目录放到 /home/app/litellm_custom/ 下。
  2. service 里设 PYTHONPATH=/home/app/litellm_custom 让 litellm 进程能 import。
  3. config.yaml 注册回调 —— 引用**实例**(不是类), 路径最后一段是小写实例名:
       litellm_settings:
         callbacks: [custom_callbacks.inflight_logger.inflight_logger]
  4. 设环境变量覆盖推送地址(默认已指向生产 monitor 57:8790,
     本机开发测试时再设 INFLIGHT_NOTIFY_URL=http://127.0.0.1:8790/api/inflight):
       INFLIGHT_NOTIFY_URL=http://192.168.3.57:8790/api/inflight
  5. 重启 LiteLLM: sudo systemctl restart litellm

设计要点:
  - 所有推送走单线程有界队列 (queue.Queue maxsize=1000), 不 per-event 起线程;
    队列满时丢最旧的一条, 监控挂了不影响 LiteLLM 转发。
  - pre_call 推送估算 token (prompt_tokens_est)。
  - finish 去重: async_post_call_success_hook 与 async_log_success_event 都可能触发,
    用 _mark_finished 保证同一 request_id 只推一次 finish (谁先到算谁的)。
    这样既覆盖「流式 /v1/messages → openai/ 后端不发 success_event」的兜底, 又不会
    在两者都触发时重复推两次。
  - pre_call 不再同步跑 litellm.token_counter() —— 大上下文(200K~1M token)同步计数
    会阻塞 async event loop; 改用字符数/3 的纯本地估算。
  - 估算输入 token 时把 system + messages + tools 都算进去 (Claude 大量 token 来自
    system prompt 和 tools, 只算 messages 会明显低估)。
  - 不发送原始 API key (只发 key_alias 人名), 避免敏感信息泄露。
  - async_pre_call_hook 显式 return data 放行请求 (return None 也行, 但显式更安全)。
"""
from __future__ import annotations
import os, json, time, queue, threading, logging, urllib.request
from collections import deque

# ── 不同 LiteLLM 版本 import 路径不同, 兼容 ──
# import 失败就 raise, 而不是退化成 object —— 否则注册到 config 后调不到真正的基类,
# 会出现 "missing 1 required positional argument: 'self'" 之类的诡异错误。
try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:
    try:
        from litellm.proxy.loggers import CustomLogger
    except ImportError as exc:
        raise ImportError(
            "无法导入 LiteLLM CustomLogger: 请确认 PYTHONPATH 指向正确且 litellm 版本"
            "含 custom_logger (litellm.integrations.custom_logger / litellm.proxy.loggers)"
        ) from exc

# 默认指向生产 monitor 采集器(192.168.3.57:8790)。
# 本机开发测试时设 INFLIGHT_NOTIFY_URL=http://127.0.0.1:8790/api/inflight 覆盖。
NOTIFY_URL = os.environ.get("INFLIGHT_NOTIFY_URL", "http://192.168.3.57:8790/api/inflight")
NOTIFY_TIMEOUT = float(os.environ.get("INFLIGHT_NOTIFY_TIMEOUT", "2"))
QUEUE_MAX = int(os.environ.get("INFLIGHT_QUEUE_MAX", "1000"))

_log = logging.getLogger("custom_callbacks.inflight_logger")

# ── ④ 单线程有界队列 worker (替代 per-event threading.Thread) ──
# 模块加载时启动一个 daemon 消费线程, 所有 hook 只往队列塞 payload。
# 队列满时丢最旧的一条 (get_nowait + put), 保证不阻塞 litellm event loop。
_QUEUE: "queue.Queue[dict]" = queue.Queue(maxsize=QUEUE_MAX)
_DROPPED = 0  # 丢弃计数 (调试用, 无锁; 仅为观察)


def _queue_worker():
    """消费线程: 循环取队列 payload 发 HTTP, 失败静默。"""
    while True:
        payload = _QUEUE.get()
        try:
            b = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                NOTIFY_URL, data=b,
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=NOTIFY_TIMEOUT).read()
        except Exception:
            pass  # 监控不可达时静默吞掉, 不影响 LiteLLM
        finally:
            _QUEUE.task_done()


def _enqueue(payload: dict):
    """往队列塞 payload; 满时丢最旧的一条腾位置。"""
    global _DROPPED
    try:
        _QUEUE.put_nowait(payload)
    except queue.Full:
        try:
            _QUEUE.get_nowait()  # 丢最旧
            _DROPPED += 1
            _QUEUE.put_nowait(payload)
        except Exception:
            pass  # 极端情况连丢都失败, 放弃


# 模块加载时启动消费线程 (只启动一次)
_WORKER_STARTED = False
if not _WORKER_STARTED:
    threading.Thread(target=_queue_worker, daemon=True).start()
    _WORKER_STARTED = True


# ── finish 去重 ──
# 同一请求可能被多个 hook 各自尝试推 finish (post_call 兜底 + success_event 标准),
# 用带序号的 set 保证每个 request_id 只推一次 finish。单进程内 set+deque 即可, 无需
# 跨进程锁 —— 一个请求只落在它所在的那个 worker 进程, 不会跨进程撞 id。
_FINISHED_IDS: "set[str]" = set()
_FINISHED_QUEUE: "deque[str]" = deque()
_FINISHED_MAX = 5000


def _mark_finished(rid: str) -> bool:
    """标记 rid 已发 finish; 首次返回 True, 重复返回 False (去重)。"""
    if not rid:
        return True  # 没有 id 就放行, 别拦掉 (拦了反而可能漏收尾)
    if rid in _FINISHED_IDS:
        return False
    _FINISHED_IDS.add(rid)
    _FINISHED_QUEUE.append(rid)
    while len(_FINISHED_QUEUE) > _FINISHED_MAX:
        _FINISHED_IDS.discard(_FINISHED_QUEUE.popleft())
    return True


# 这些 key 存的是 base64 图片/音频/文件二进制, 拍平只会得到一大坨乱码, 跳过。
_SKIP_LARGE_BINARY_KEYS = {"data", "image_data", "audio_data"}


def _flatten(obj) -> str:
    """把 messages/input/tools (可能嵌套 dict/list, Anthropic content 块) 拍平成纯文本。

    递归拍平所有字段(不再只挑 content/text 等键), 这样 system prompt、tools 定义、
    多模态 content 块里的文本都能计入; 只跳过 base64 二进制键。
    """
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (int, float, bool)):
        return str(obj)
    if isinstance(obj, list):
        return " ".join(_flatten(x) for x in obj)
    if isinstance(obj, dict):
        return " ".join(
            _flatten(v) for k, v in obj.items()
            if k not in _SKIP_LARGE_BINARY_KEYS)
    return str(obj)


def _estimate_tokens(data: dict) -> int:
    """估算输入 token 数。纯本地字符数/3, 不做同步 tokenizer 调用。

    把 system + messages + tools + input + prompt 全算进去 (Claude 大量 token 来自
    system prompt 和 tools, 只算 messages 会明显低估)。字符/3 是中英代码混合的折中值,
    够用来判断"超大上下文", 且绝不阻塞 event loop。
    """
    parts = [data.get("system"), data.get("system_prompt"), data.get("instructions"),
             data.get("messages"), data.get("input"), data.get("prompt"), data.get("tools")]
    text = " ".join(_flatten(part) for part in parts if part is not None)
    if not text:
        return 0
    return max(1, int(len(text) / 3))


def _extract_usage(response_obj) -> "tuple[int, int]":
    """从 response 取 (prompt_tokens, completion_tokens), 兼容 dict/对象两种形态。"""
    if isinstance(response_obj, dict):
        u = response_obj.get("usage")
    else:
        u = getattr(response_obj, "usage", None)
    if not u:
        return 0, 0
    get = u.get if isinstance(u, dict) else (lambda k, d=0: getattr(u, k, d))
    pt = get("prompt_tokens", get("input_tokens", 0)) or 0
    ct = get("completion_tokens", get("output_tokens", 0)) or 0
    return int(pt or 0), int(ct or 0)


def _extract_ip(data: dict) -> str:
    """从 pre_call data 提取客户端 IP。

    LiteLLM 代理的 pre_call 阶段, IP 藏在几个地方, 按可靠度依次试:
      1) proxy_server_request: starlette Request **对象**(不是 dict, 之前按 dict 取 .get("headers")
         会静默失败导致 IP 恒为空), 用 getattr 取 .headers / .client;
         - x-forwarded-for / x-real-ip (反代场景, 第一个是真实客户端)
         - client.host (直连)
      2) metadata.requester_ip_address / user_ip / client_ip (部分版本代理已解析好塞进 metadata)
      3) 顶层 requester_ip_address / user_ip / client_ip (兜底)
    """
    # 1) proxy_server_request 是 Request 对象
    req = data.get("proxy_server_request")
    if req is not None:
        try:
            headers = getattr(req, "headers", None)
            if headers is not None:
                xff = (headers.get("x-forwarded-for") or headers.get("X-Forwarded-For") or "")
                if xff:
                    return str(xff).split(",")[0].strip()
                xri = (headers.get("x-real-ip") or headers.get("X-Real-IP") or "")
                if xri:
                    return str(xri).strip()
        except Exception:
            pass
        try:
            client = getattr(req, "client", None)
            if client:
                host = getattr(client, "host", None)
                if host:
                    return str(host)
        except Exception:
            pass
    # 2) metadata 里代理解析好的
    md = data.get("metadata") or {}
    if isinstance(md, dict):
        for k in ("requester_ip_address", "user_ip", "client_ip"):
            v = md.get(k)
            if v:
                return str(v)
    # 3) 顶层兜底
    for k in ("requester_ip_address", "user_ip", "client_ip"):
        v = data.get(k)
        if v:
            return str(v)
    return ""


def _get_rid(data: dict) -> str:
    """取 request id (litellm_call_id 优先)。"""
    return data.get("litellm_call_id") or data.get("request_id") or ""


# 只统计这些模型前缀的在途请求; 其余(如 kimi / embedding / 别的业务模型)不推。
# 环境变量 INFLIGHT_GLM_PREFIX 可配, 默认 "GLM-5.2-Int8" (与 monitor.py 的 is_glm_model 一致)。
GLM_MODEL_PREFIX = os.environ.get("INFLIGHT_GLM_PREFIX", "GLM-5.2-Int8")


def _is_glm_model(model) -> bool:
    """判断模型是否在统计范围内。空模型按非 GLM 处理(不推)。"""
    if not model:
        return False
    return str(model).startswith(GLM_MODEL_PREFIX)


class InflightLogger(CustomLogger):
    """LiteLLM 代理回调: pre_call 上报在途(估算), success/failure 推 finish(真实)。"""

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        # ③ try 外 return data: 即使 try 内异常也放行请求, 绝不影响转发
        try:
            model = data.get("model") or ""
            if not _is_glm_model(model):
                return data  # 非 GLM 模型不纳入在途统计
            rid = _get_rid(data)
            # ① 只取 key_alias(人名), 不发原始 token
            name = getattr(user_api_key_dict, "key_alias", "") or ""
            ptok_est = _estimate_tokens(data)
            ip = _extract_ip(data)  # ②
            _log.info("InflightLogger START rid=%s name=%s ip=%s est=%d model=%s",
                      rid, name, ip, ptok_est, model)
            _enqueue({
                "action": "start",
                "request_id": rid,
                "name": name,
                "ip": ip,
                "model": str(model),
                "prompt_tokens_est": ptok_est,
                "ts": time.time(),
            })
        except Exception:
            pass  # 回调绝不能影响请求转发
        return data  # ③ 显式放行 (return None 也行, 但显式更安全)

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        """兜底推 finish (带去重), 不是纯透传。

        为什么这里推 finish: 流式 /v1/messages → openai/ 后端场景下, 部分 LiteLLM 版本
        不会发出 async_log_success_event, 若这里不透传 finish, 该请求会在监控页永远
        RUNNING。去重靠 _mark_finished —— 若 success_event 已先推过, 这里直接跳过。
        此钩子没有 start_time/end_time, duration 记 0。
        """
        try:
            model = data.get("model") or ""
            if not _is_glm_model(model):
                return response  # 非 GLM 模型, start 也没推, finish 一并跳过
            rid = _get_rid(data)
            if not _mark_finished(rid):
                return response  # success_event 已先发过 finish, 不重复
            ptok_actual, ct = _extract_usage(response)
            _log.info("InflightLogger FINISH(fallback) rid=%s pt=%d ct=%d",
                      rid, ptok_actual, ct)
            _enqueue({
                "action": "finish",
                "request_id": rid,
                "status": "success",
                "prompt_tokens_actual": ptok_actual,
                "completion_tokens": ct,
                "duration_ms": 0,
                "ts": time.time(),
            })
        except Exception:
            pass
        return response

    async def async_post_call_failure_hook(self, request_data, original_exception,
                                           user_api_key_dict, traceback_str=None):
        """兜底推 finish (带去重), 覆盖客户端主动终止/取消/连接断开等场景。

        客户端主动断开流式请求时, LiteLLM 可能不触发 async_log_failure_event,
        而是走这个 post_call_failure 钩子。若这里不透传 finish, 该请求会在监控页
        一直 RUNNING 且耗时无限累加。去重靠 _mark_finished。
        """
        try:
            data = request_data or {}
            model = data.get("model") or ""
            if not _is_glm_model(model):
                return
            rid = _get_rid(data)
            if not _mark_finished(rid):
                return
            exc_name = type(original_exception).__name__ if original_exception else "cancel_or_disconnect"
            _log.info("InflightLogger FINISH(failure_hook) rid=%s exc=%s", rid, exc_name)
            _enqueue({
                "action": "finish",
                "request_id": rid,
                "status": "failure",
                "ts": time.time(),
            })
        except Exception:
            pass

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        try:
            model = kwargs.get("model") or ""
            if not _is_glm_model(model):
                return  # 非 GLM 模型, 不推
            rid = _get_rid(kwargs)
            if not _mark_finished(rid):
                return  # post_call 兜底已先发过 finish, 不重复
            # ⑤ 真实 token: 从 response.usage 取
            ptok_actual, ct = _extract_usage(response_obj)
            dur = 0.0
            try:
                if start_time and end_time:
                    dur = (end_time - start_time).total_seconds() * 1000
            except Exception:
                pass
            _log.info("InflightLogger FINISH rid=%s status=success pt=%d ct=%d dur=%d",
                      rid, ptok_actual, ct, round(dur))
            _enqueue({
                "action": "finish",  # ⑤ 区别于 end: 带真实 token, monitor 走 grace
                "request_id": rid,
                "status": "success",
                "prompt_tokens_actual": ptok_actual,
                "completion_tokens": ct,
                "duration_ms": round(dur),
                "ts": time.time(),
            })
        except Exception:
            pass

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        try:
            model = kwargs.get("model") or ""
            if not _is_glm_model(model):
                return  # 非 GLM 模型, 不推
            rid = _get_rid(kwargs)
            if not _mark_finished(rid):
                return
            _log.info("InflightLogger FINISH rid=%s status=failure", rid)
            _enqueue({
                "action": "finish",  # failure 也走 finish, monitor 标记 failed + grace
                "request_id": rid,
                "status": "failure",
                "ts": time.time(),
            })
        except Exception:
            pass


# ── 实例化: LiteLLM 当前自定义 callback 的用法是「先实例化, 再在配置里引用实例」──
# config.yaml 里写 callbacks: [custom_callbacks.inflight_logger.inflight_logger]
# (最后一段是小写实例名, 不是类名)。没有这行, 注册类名会触发 missing self。
inflight_logger = InflightLogger()
