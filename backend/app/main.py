"""FastAPI application factory for FraudShield AI.

Wires configuration, structured logging, CORS, the global error-handler and
rate-limiter middleware, and mounts the v1 routers. Member A's routers (auth,
submissions, verdicts, dashboard) are always mounted; teammates' routers
(analysis, clusters, chat, virustotal) are mounted opportunistically so the app
still boots on a fresh `feat/m1-*` branch.

Run locally:  uvicorn app.main:app --reload
Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging import bind_request_id, clear_request_context, configure_logging, get_logger
from app.middlewares.error_handler import register_exception_handlers
from app.middlewares.rate_limiter import RateLimiterMiddleware

log = get_logger(__name__)


def create_app() -> FastAPI:
    configure_logging()

    app = FastAPI(
        title=settings.APP_NAME,
        version="1.0.0",
        description="GenAI-based automated analysis & risk scoring of fraudulent APKs.",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    # ── CORS ────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Rate limiting (login throttle etc.) ─────────────────────────────
    app.add_middleware(RateLimiterMiddleware)

    # ── request_id tracing ──────────────────────────────────────────────
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        bind_request_id(request_id)
        try:
            response = await call_next(request)
        finally:
            clear_request_context()
        response.headers["X-Request-ID"] = request_id
        return response

    # ── standardized error envelope ─────────────────────────────────────
    register_exception_handlers(app)

    # ── health / liveness ───────────────────────────────────────────────
    @app.get("/health", tags=["meta"])
    def health():
        return JSONResponse({"status": "ok", "service": settings.APP_NAME})

    _mount_routers(app)
    log.info("app.started", environment=settings.ENVIRONMENT)
    return app


def _mount_routers(app: FastAPI) -> None:
    prefix = settings.API_V1_PREFIX

    # Member A — always available on this branch.
    from app.api.v1 import auth, dashboard, submissions, verdicts

    app.include_router(auth.router, prefix=prefix)
    app.include_router(submissions.router, prefix=prefix)
    app.include_router(verdicts.router, prefix=prefix)
    app.include_router(dashboard.router, prefix=prefix)

    # Teammates' routers — mount if present (parallel-dev friendly).
    for module_name in ("analysis", "clusters", "chat", "virustotal"):
        try:  # pragma: no cover
            module = __import__(f"app.api.v1.{module_name}", fromlist=["router"])
            app.include_router(module.router, prefix=prefix)
        except Exception:  # noqa: BLE001
            log.debug("router.skipped", module=module_name)


app = create_app()
