"""Structured logging configuration (structlog).

Emits one JSON object per line to stdout so Railway/Vercel log streams can parse
them. Every request is tagged with a `request_id` (bound in the error-handler /
request-id middleware) so a single submission can be traced across the
static → dynamic → sanitize → LLM → scoring pipeline.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import logging
import sys

import structlog

from app.core.config import settings


def configure_logging() -> None:
    """Configure structlog + stdlib logging. Call once at app startup."""
    level = logging.DEBUG if settings.DEBUG else logging.INFO

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Human-friendly console in dev, JSON everywhere else.
    if settings.is_production:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)


def bind_request_id(request_id: str) -> None:
    """Bind a request_id into contextvars so every log line in this request carries it."""
    structlog.contextvars.bind_contextvars(request_id=request_id)


def clear_request_context() -> None:
    structlog.contextvars.clear_contextvars()
