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


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
