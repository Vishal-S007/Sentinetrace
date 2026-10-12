"""Application settings, loaded from environment variables (never hardcoded secrets)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ST_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    app_name: str = "SentinelTrace"
    version: str = "0.1.0"

    # Required: no default, so a missing DB URL fails loudly at startup.
    database_url: PostgresDsn

    # Comma-separated list of allowed browser origins. Empty means no cross-origin access.
    cors_origins: str = Field(default="")

    # Upload limits (enforced from Phase 3 onward).
    max_upload_bytes: int = Field(default=50 * 1024 * 1024, gt=0)

    # Sessions
    session_idle_minutes: int = Field(default=60, gt=0)
    session_absolute_hours: int = Field(default=12, gt=0)
    # None = secure cookies only in production. Set true when serving over HTTPS.
    cookie_secure: bool | None = None

    # Login rate limiting (failed attempts inside the sliding window)
    login_window_seconds: int = Field(default=900, gt=0)
    login_max_failures_per_user: int = Field(default=5, gt=0)
    login_max_failures_per_ip: int = Field(default=20, gt=0)

    @field_validator("database_url")
    @classmethod
    def require_psycopg_driver(cls, v: PostgresDsn) -> PostgresDsn:
        if v.scheme not in ("postgresql+psycopg",):
            raise ValueError("ST_DATABASE_URL must use the postgresql+psycopg:// scheme")
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def secure_cookies(self) -> bool:
        return self.is_production if self.cookie_secure is None else self.cookie_secure


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
