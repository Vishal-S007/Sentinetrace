"""Application settings, loaded from environment variables (never hardcoded secrets)."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ST_",
        env_ignore_empty=True,  # "ST_X=" in .env or Compose means "use the default"
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

    # Ingestion
    storage_dir: Path = Path("storage")
    max_line_bytes: int = Field(default=16 * 1024, gt=0)
    max_lines_per_file: int = Field(default=5_000_000, gt=0)
    max_errors_per_job: int = Field(default=10_000, ge=0)
    ingest_batch_size: int = Field(default=1000, gt=0, le=10_000)
    worker_poll_seconds: float = Field(default=1.0, gt=0)
    job_stale_minutes: int = Field(default=10, gt=0)
    max_job_attempts: int = Field(default=3, gt=0)
    # The worker touches this file after each successful poll of the database; the
    # container health check (`python -m app.worker --check-health`) reads its age.
    worker_heartbeat_file: Path | None = None

    # Retention (see docs: never touches open alerts, incidents, notes or the audit log)
    retention_min_days: int = Field(default=7, ge=1)
    # If set, the worker purges data older than this many days once a day.
    retention_auto_days: int | None = Field(default=None, ge=1)
    retention_batch_size: int = Field(default=5000, ge=100, le=100_000)

    # Abuse limits on expensive read endpoints (exports and reports), per user per minute
    export_rate_per_minute: int = Field(default=10, ge=1)

    # Detection
    alert_group_minutes: int = Field(default=60, ge=5, le=1440)
    max_evidence_per_alert: int = Field(default=500, ge=10, le=100_000)
    detection_chunk_hours: int = Field(default=24, ge=1, le=24 * 31)

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
