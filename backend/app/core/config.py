"""Application configuration.

Central Pydantic-Settings object that reads every runtime secret / connection
string from the environment (see `backend/.env.example`). Imported everywhere as
`from app.core.config import settings`.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── App meta ────────────────────────────────────────────────────────
    APP_NAME: str = "FraudShield AI"
    ENVIRONMENT: str = Field(default="development")  # development|staging|production
    DEBUG: bool = Field(default=True)
    API_V1_PREFIX: str = "/api/v1"

    # ── Database (Member A) ─────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="postgresql+psycopg2://fraudshield:fraudshield@localhost:5432/fraudshield"
    )

    # ── Auth / JWT (Member A) ───────────────────────────────────────────
    JWT_SECRET: str = Field(default="change-me-in-production")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Cache / broker (Member C) ───────────────────────────────────────
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    RABBITMQ_URL: str = Field(default="amqp://guest:guest@localhost:5672//")

    # ── Object storage (Member A) ───────────────────────────────────────
    STORAGE_BUCKET: str = Field(default="fraudshield-apks")
    STORAGE_KEY: str = Field(default="")
    STORAGE_SECRET: str = Field(default="")
    STORAGE_ENDPOINT_URL: str | None = Field(default=None)  # e.g. Backblaze B2 endpoint
    STORAGE_REGION: str = Field(default="us-east-005")

    # ── External services ───────────────────────────────────────────────
    CLAUDE_API_KEY: str = Field(default="")        # Member B
    VIRUSTOTAL_API_KEY: str = Field(default="")    # Member C

    # ── Upload limits ───────────────────────────────────────────────────
    MAX_UPLOAD_BYTES: int = 200 * 1024 * 1024  # 200 MB per §5 API spec

    # ── CORS ────────────────────────────────────────────────────────────
    CORS_ORIGINS: List[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    """Cached accessor so the env is parsed once per process."""
    return Settings()


settings = get_settings()
