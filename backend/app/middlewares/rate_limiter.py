"""Rate-limiting middleware.

Sliding-window limiter keyed by client IP + route. The primary target is
brute-force protection on `POST /auth/login` (5 attempts / minute / IP), but the
rule table is generic so other sensitive routes can be added.

Backed by Redis when `REDIS_URL` is reachable (correct across multiple API
replicas); falls back to an in-process window so local dev and tests work with
no broker running.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

# (method, path_prefix) -> (max_requests, window_seconds)
RATE_RULES: dict[tuple[str, str], tuple[int, int]] = {
    ("POST", f"{settings.API_V1_PREFIX}/auth/login"): (5, 60),
    ("POST", f"{settings.API_V1_PREFIX}/auth/register"): (10, 60),
}


class _InMemoryWindow:
    """Per-process sliding window. Good enough for dev/tests/single replica."""

    def __init__(self) -> None:
        self._hits: dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        q = self._hits[key]
        cutoff = now - window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


class _RedisWindow:
    """Redis-backed fixed window using INCR + EXPIRE. Shared across replicas."""

    def __init__(self, client) -> None:
        self._r = client

    def allow(self, key: str, limit: int, window: int) -> bool:
        bucket = int(time.time() // window)
        redis_key = f"rl:{key}:{bucket}"
        count = self._r.incr(redis_key)
        if count == 1:
            self._r.expire(redis_key, window)
        return count <= limit


def _build_backend():
    try:  # pragma: no cover - depends on a running Redis
        import redis

        client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.2)
        client.ping()
        log.info("rate_limiter.backend", backend="redis")
        return _RedisWindow(client)
    except Exception:  # noqa: BLE001
        log.info("rate_limiter.backend", backend="in_memory")
        return _InMemoryWindow()


class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._backend = _build_backend()

    def _match_rule(self, method: str, path: str) -> tuple[int, int] | None:
        for (rule_method, prefix), limits in RATE_RULES.items():
            if method == rule_method and path.startswith(prefix):
                return limits
        return None

    async def dispatch(self, request: Request, call_next):
        rule = self._match_rule(request.method, request.url.path)
        if rule is None:
            return await call_next(request)

        limit, window = rule
        client_ip = request.client.host if request.client else "unknown"
        key = f"{request.method}:{request.url.path}:{client_ip}"

        if not self._backend.allow(key, limit, window):
            request_id = request.headers.get("X-Request-ID", "-")
            log.warning("rate_limited", ip=client_ip, path=request.url.path)
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "rate_limited",
                        "message": f"Too many requests. Limit {limit}/{window}s.",
                        "request_id": request_id,
                    }
                },
                headers={"Retry-After": str(window)},
            )
        return await call_next(request)
