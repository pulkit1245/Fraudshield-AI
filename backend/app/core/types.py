"""Portable SQLAlchemy column types.

Production runs on PostgreSQL (native UUID + JSONB), but the CI/unit test suite
runs against in-memory SQLite so it needs no live database. These aliases resolve
to the Postgres-native type on Postgres and a portable fallback everywhere else:

    UUID  -> PostgreSQL UUID  | CHAR(32) on SQLite
    JSONB -> PostgreSQL JSONB | JSON (TEXT) on SQLite

Import these in the ORM models instead of `sqlalchemy.dialects.postgresql`.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

from sqlalchemy import JSON, Uuid
from sqlalchemy.dialects.postgresql import JSONB as _PG_JSONB

# Native UUID on PG, CHAR(32) on other dialects (SQLAlchemy 2.0 `Uuid`).
UUID = Uuid

# One shared portable JSON type instance (JSONB on PG, JSON elsewhere).
JSONB = JSON().with_variant(_PG_JSONB(), "postgresql")
