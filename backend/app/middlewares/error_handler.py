"""Global exception handling → standard error envelope.

Every error response has the shape:

    {"error": {"code": <str>, "message": <str>, "request_id": <str>}}

matching the §1 "Caching, Error Handling & Logging" contract. Registered on the
app in `app.main.create_app`.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger

log = get_logger(__name__)

# Map common HTTP status codes to stable, machine-readable error codes.
_STATUS_CODE_MAP: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
}


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID", "-")


def _envelope(code: str, message, request_id: str, http_status: int) -> JSONResponse:
    return JSONResponse(
        status_code=http_status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
    )


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exc_handler(request: Request, exc: StarletteHTTPException):
        code = _STATUS_CODE_MAP.get(exc.status_code, "error")
        return _envelope(code, exc.detail, _request_id(request), exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_exc_handler(request: Request, exc: RequestValidationError):
        return _envelope(
            "validation_error",
            exc.errors(),
            _request_id(request),
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    @app.exception_handler(Exception)
    async def unhandled_exc_handler(request: Request, exc: Exception):
        # Never leak internals to the client; full trace goes to structured logs.
        log.error("unhandled_exception", error=str(exc), path=request.url.path, exc_info=exc)
        return _envelope(
            "internal_error",
            "An unexpected error occurred.",
            _request_id(request),
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
