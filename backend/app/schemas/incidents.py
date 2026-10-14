"""Schemas for incidents: grouping related alerts, notes, timeline and reports."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.detection import AlertOut, NoteOut, Severity

IncidentStatus = Literal["open", "investigating", "contained", "resolved", "closed"]
MAX_ALERTS_PER_REQUEST = 200


def _strip_required(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("must not be blank")
    return v


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(default="", max_length=10_000)
    severity: Severity | None = Field(
        default=None, description="Defaults to the highest severity among the linked alerts"
    )
    assigned_to: int | None = None
    alert_ids: list[int] = Field(default_factory=list, max_length=MAX_ALERTS_PER_REQUEST)

    _title = field_validator("title")(_strip_required)


class IncidentUpdate(BaseModel):
    """Partial update. `assigned_to: null` clears the owner."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=200)
    summary: str | None = Field(default=None, max_length=10_000)
    status: IncidentStatus | None = None
    severity: Severity | None = None
    assigned_to: int | None = None
    note: str = Field(default="", max_length=1000)

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, v: str | None) -> str | None:
        return None if v is None else _strip_required(v)

    @model_validator(mode="after")
    def something_changes(self) -> "IncidentUpdate":
        fields = {"title", "summary", "status", "severity"}
        if all(getattr(self, f) is None for f in fields) and (
            "assigned_to" not in self.model_fields_set
        ):
            raise ValueError("provide at least one field to change")
        return self


class LinkAlerts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_ids: list[int] = Field(min_length=1, max_length=MAX_ALERTS_PER_REQUEST)


class IncidentOut(BaseModel):
    id: int
    title: str
    summary: str
    status: IncidentStatus
    severity: Severity
    assigned_to: int | None
    assignee: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    alert_count: int


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    next_before_id: int | None


TimelineKind = Literal["observed", "change", "note"]


class TimelineItem(BaseModel):
    at: datetime
    kind: TimelineKind
    title: str
    detail: str | None = None
    actor: str | None = None
    alert_id: int | None = None
    event_id: int | None = None


class IncidentDetailOut(IncidentOut):
    alerts: list[AlertOut]
    notes: list[NoteOut]
    timeline: list[TimelineItem]
