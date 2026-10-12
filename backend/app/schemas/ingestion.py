"""Schemas for log sources, uploads and ingestion jobs."""

from datetime import datetime
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.ingestion.parsers import PatternError, compile_log_format

SourceFormat = Literal[
    "auto", "apache_combined", "nginx_combined", "nginx_common", "nginx_custom", "json", "auth_log"
]
UploadFormat = Literal[
    "apache_combined", "nginx_combined", "nginx_common", "nginx_custom", "json", "auth_log"
]
JobStatus = Literal["queued", "running", "completed", "completed_with_errors", "failed"]


def _check_timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            f"unknown time zone '{value}' (use an IANA name like 'Asia/Kolkata')"
        ) from exc
    return value


def _check_pattern(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        compile_log_format(value)
    except PatternError as exc:
        raise ValueError(str(exc)) from exc
    return " ".join(value.split())


class SourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    format: SourceFormat = "auto"
    custom_pattern: str | None = Field(default=None, max_length=2000)
    timezone: str = Field(default="UTC", max_length=64)

    _tz = field_validator("timezone")(_check_timezone)
    _pattern = field_validator("custom_pattern")(_check_pattern)

    @field_validator("name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @model_validator(mode="after")
    def pattern_required(self) -> "SourceCreate":
        if self.format == "nginx_custom" and not self.custom_pattern:
            raise ValueError(
                "custom_pattern (an nginx log_format string) is required for nginx_custom"
            )
        return self


class SourceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    format: SourceFormat | None = None
    custom_pattern: str | None = Field(default=None, max_length=2000)
    timezone: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None

    @field_validator("timezone")
    @classmethod
    def tz(cls, v: str | None) -> str | None:
        return None if v is None else _check_timezone(v)

    _pattern = field_validator("custom_pattern")(_check_pattern)


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    format: SourceFormat
    custom_pattern: str | None
    timezone: str
    enabled: bool
    created_at: datetime
    file_count: int = 0
    event_count: int = 0
    last_upload_at: datetime | None = None


class FormatOut(BaseModel):
    id: str
    label: str
    example: str
    detectable: bool


class FileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_id: int
    original_filename: str
    sha256: str
    size_bytes: int
    encoding: str
    uploaded_at: datetime


class JobOut(BaseModel):
    id: int
    status: JobStatus
    source_id: int
    source_name: str
    file_id: int
    filename: str
    size_bytes: int
    encoding: str
    requested_format: str | None
    format: str | None
    total_lines: int
    parsed_count: int
    rejected_count: int
    duplicate_count: int
    errors_truncated: bool
    error_message: str | None
    attempts: int
    created_by: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class UploadResult(BaseModel):
    file: FileOut
    job: JobOut


class JobPage(BaseModel):
    items: list[JobOut]
    next_before_id: int | None


class IngestionErrorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    line_number: int
    reason: str
    raw_line: str


class ErrorPage(BaseModel):
    items: list[IngestionErrorOut]
    next_after_id: int | None
    total_rejected: int
    stored: int
    truncated: bool
