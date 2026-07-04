"""Database engine, session factory and declarative Base.

Shared SQLAlchemy foundation for the whole backend. Every member's ORM model
inherits from `Base`; request handlers get a session via `get_db()` (FastAPI
dependency) and Celery tasks via `session_scope()`.

The engine and sessionmaker are created lazily on first use, so simply importing
this module (or the ORM models) does not require the production DB driver to be
installed — the test suite can run on SQLite without psycopg2.

Owner: Member A — Backend Lead (scaffold shared by all members).
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker] = None


class Base(DeclarativeBase):
    """Declarative base every ORM model inherits from."""
    pass


def get_engine() -> Engine:
    """Lazily create (once) and return the process-wide SQLAlchemy engine."""
    global _engine
    if _engine is None:
        # pool_pre_ping recycles dead connections (managed PG drops idle ones).
        _engine = create_engine(
            settings.DATABASE_URL,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            future=True,
        )
    return _engine


def get_sessionmaker() -> sessionmaker:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
            class_=Session,
        )
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a request-scoped session."""
    db = get_sessionmaker()()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Transactional scope for Celery workers / scripts.

    Commits on success, rolls back on exception, always closes.
    """
    db = get_sessionmaker()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
