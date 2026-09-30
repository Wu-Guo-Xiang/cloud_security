"""认证核心：单一管理员(env 配置) + 签名 session + 登录限流 + CSRF。

设计要点：
- 密码优先 bcrypt 哈希(AUDIT_ADMIN_PASSWORD_HASH)；未配置哈希时回退明文 env
  (AUDIT_ADMIN_PASSWORD)，用 secrets.compare_digest 常量时间比较。
- 两者都为空 → fail-closed：登录一律拒绝，不默认弱口令。
- 认证用中间件(不改现有路由签名)；CSRF 用依赖只加在表单类 POST 上。
- session 由 Starlette SessionMiddleware 提供(签名 cookie)，本模块只读写 request.session。
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from urllib.parse import quote

from fastapi import Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

# ── 公开路径白名单(免登录) ──────────────────────────────────────
# /login /logout        认证端点本身
# /ingest               客户端数据上报(已有 X-Ingest-Token 鉴权)
# /plugins/manifest.json /plugins/download/*  客户端插件自动更新链路
# /static/*             静态资源(登录页渲染前就要能取到 css/logo)
PUBLIC_EXACT = {"/login", "/logout", "/ingest", "/plugins/manifest.json", "/managed-settings.json", "/install.ps1"}
PUBLIC_PREFIXES = ("/static/", "/plugins/download/", "/api/hooks/")


class AuthConfig:
    """从环境变量读取单一管理员凭证。"""

    def __init__(self) -> None:
        self.admin_user = os.environ.get("AUDIT_ADMIN_USER", "admin").strip()
        pw_hash = os.environ.get("AUDIT_ADMIN_PASSWORD_HASH", "").strip()
        pw_plain = os.environ.get("AUDIT_ADMIN_PASSWORD", "").strip()
        # 优先哈希；无哈希才接受明文回退
        self.password_hash: str | None = pw_hash or None
        self.password_plain: str | None = pw_plain or None
        self.enabled = bool(self.password_hash or self.password_plain)

        secret = os.environ.get("AUDIT_SESSION_SECRET", "").strip()
        # 未配置固定密钥 → 每次启动随机(重启需重登，单管理员场景可接受)
        self.session_secret = secret or secrets.token_urlsafe(32)
        self.https_only = os.environ.get("AUDIT_BEHIND_HTTPS", "0").strip().lower() in (
            "1", "true", "yes", "on",
        )

    def warn_if_disabled(self) -> None:
        if not self.enabled:
            import sys
            sys.stderr.write(
                "[auth] 警告：未配置 AUDIT_ADMIN_PASSWORD_HASH / AUDIT_ADMIN_PASSWORD，"
                "登录已禁用(fail-closed)。请在 docker-compose 环境变量中配置管理员凭证。\n"
            )


def verify_password(submitted: str, cfg: AuthConfig) -> bool:
    """校验提交的密码。未启用认证 → 一律拒绝。"""
    if not cfg.enabled or not submitted:
        return False
    if cfg.password_hash:
        try:
            import bcrypt
            return bcrypt.checkpw(
                submitted.encode("utf-8"),
                cfg.password_hash.encode("utf-8"),
            )
        except Exception:
            return False
    # 明文回退：常量时间比较，避免时序侧信道
    return secrets.compare_digest(submitted, cfg.password_plain or "")


class RateLimiter:
    """内存登录限流：按 key(用户名+客户端IP) 记失败次数，超阈值锁定。"""

    def __init__(self, max_failures: int = 5, lock_seconds: int = 60) -> None:
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._fails: dict[str, list] = {}  # key -> [count, lock_until_ts]
        self._lock = threading.Lock()

    @staticmethod
    def key_for(username: str, request: Request) -> str:
        ip = request.client.host if request.client else "?"
        return f"{username or '?'}@{ip}"

    def is_locked(self, key: str) -> bool:
        with self._lock:
            rec = self._fails.get(key)
            if not rec:
                return False
            count, lock_until = rec
            if lock_until and time.time() < lock_until:
                return True
            if lock_until:  # 锁已过期，清掉
                self._fails.pop(key, None)
            return False

    def record_failure(self, key: str) -> None:
        with self._lock:
            rec = self._fails.get(key, [0, 0.0])
            rec[0] += 1
            if rec[0] >= self.max_failures:
                rec[1] = time.time() + self.lock_seconds
            self._fails[key] = rec

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)


def _wants_html(request: Request) -> bool:
    """浏览器导航(Accept: text/html)→重定向;fetch/JSON→401。"""
    accept = request.headers.get("accept", "").lower()
    return "text/html" in accept or "application/xhtml" in accept


def is_public(path: str) -> bool:
    return path in PUBLIC_EXACT or path.startswith(PUBLIC_PREFIXES)


async def check_auth(request: Request, call_next, cfg: AuthConfig):
    """认证中间件：未登录拦截，已登录放行。session 由 SessionMiddleware 注入。"""
    if is_public(request.url.path):
        return await call_next(request)
    # 防御性读取：SessionMiddleware 正常情况下已注入 scope["session"]；
    # 若因中间件顺序异常未注入，则视为未登录(fail-closed)。
    session = request.scope.get("session") or {}
    if session.get("user"):
        return await call_next(request)
    # 未登录
    if _wants_html(request):
        target = quote(request.url.path, safe="/")
        return RedirectResponse(f"/login?next={target}", status_code=302)
    return JSONResponse({"error": "unauthorized"}, status_code=401)


# ── CSRF ────────────────────────────────────────────────────────
def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


async def verify_csrf(
    request: Request,
    csrf: str | None = Form(None, alias="_csrf"),
    x_csrf: str | None = Header(None, alias="X-CSRF-Token"),
) -> None:
    """表单类 POST 的 CSRF 依赖：双提交 token(session ↔ form/header)。"""
    expected = request.session.get("csrf_token")
    provided = csrf or x_csrf
    if not expected or not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=403, detail="CSRF 校验失败，请刷新页面后重试")


def safe_next(next_str: str | None) -> str:
    """只允许站内相对路径，防 open redirect。"""
    if not next_str or not next_str.startswith("/") or next_str.startswith("//"):
        return "/dashboard"
    return next_str
