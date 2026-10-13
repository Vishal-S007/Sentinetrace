"""Schemas for detection rules, alerts and detection runs."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "investigating", "resolved", "false_positive"]
Confidence = Literal["low", "medium", "high"]


class RuleOut(BaseModel):
    rule_id: str
    name: str
    category: str
    description: str
    severity: Severity
    default_severity: Severity
    enabled: bool
    version: int
    config: dict[str, Any]
    default_config: dict[str, Any]
    config_schema: dict[str, Any]
    recommended_steps: list[str]
    updated_at: datetime
    updated_by: str | None
    open_alerts: int


class RuleVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    version: int
    enabled: bool
    severity: Severity
    config: dict[str, Any]
    note: str
    changed_by: str | None = None
    changed_at: datetime


class RuleDetailOut(RuleOut):
    versions: list[RuleVersionOut]


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    severity: Severity | None = None
    config: dict[str, Any] | None = None
    note: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def something_changes(self) -> "RuleUpdate":
        if self.enabled is None and self.severity is None and self.config is None:
            raise ValueError("provide at least one of enabled, severity, config")
        return self


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    rule_name: str = ""
    rule_version: int
    title: str
    severity: Severity
    status: AlertStatus
    confidence: Confidence
    source_ip: str | None
    username: str | None
    endpoint: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    created_at: datetime
    updated_at: datetime

    @field_validator("source_ip", mode="before")
    @classmethod
    def ip_str(cls, v: Any) -> Any:
        return None if v is None else str(v)


class AlertDetailOut(AlertOut):
    reason: str
    confidence_reason: str
    recommended_action: str
    recommended_steps: list[str] = []
    window_seconds: int
    bucket_start: datetime
    evidence_truncated: bool
    evidence_count: int = 0
    details: dict[str, Any]
    assigned_to: int | None


class AlertPage(BaseModel):
    items: list[AlertOut]
    next_before_id: int | None


class EvidenceEventOut(BaseModel):
    event_id: int
    indicator: str | None
    event_time: datetime
    event_type: str
    source_ip: str | None
    username: str | None
    http_method: str | None
    path: str | None
    query: str | None
    http_status: int | None
    user_agent: str | None
    source_id: int
    file_id: int
    line_number: int
    raw_line: str


class EvidencePage(BaseModel):
    items: list[EvidenceEventOut]
    next_after_id: int | None
    total_linked: int
    total_events: int
    truncated: bool


class DetectionRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    since: datetime | None = None
    until: datetime | None = None

    @model_validator(mode="after")
    def ordered(self) -> "DetectionRunCreate":
        for v in (self.since, self.until):
            if v is not None and v.tzinfo is None:
                raise ValueError("since/until must include a time zone (e.g. ...Z)")
        if self.since and self.until and self.since > self.until:
            raise ValueError("since must be before until")
        return self


class DetectionRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    trigger: str
    status: str
    job_id: int | None
    range_start: datetime | None
    range_end: datetime | None
    alerts_created: int
    alerts_updated: int
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class AlertStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertStatus
    note: str = Field(default="", max_length=1000)
