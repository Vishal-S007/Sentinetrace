"""Schemas for the dashboard and the event explorer."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

from app.schemas.detection import AlertOut

DashboardRange = Literal["24h", "7d", "30d", "90d", "all"]


class Totals(BaseModel):
    events: int
    alerts: int
    open_alerts: int
    high_open_alerts: int
    sources: int
    files: int


class Count(BaseModel):
    key: str
    count: int


class TimePoint(BaseModel):
    bucket_start: datetime
    count: int


class SeverityPoint(BaseModel):
    bucket_start: datetime
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class TopIp(BaseModel):
    source_ip: str
    alert_count: int
    event_count: int
    max_severity: str


class TopRule(BaseModel):
    rule_id: str
    name: str
    alert_count: int


class RecentJob(BaseModel):
    id: int
    status: str
    filename: str
    source_name: str
    parsed_count: int
    rejected_count: int
    created_at: datetime


class DataRange(BaseModel):
    first_event: datetime | None
    last_event: datetime | None


class DashboardOut(BaseModel):
    range: DashboardRange
    start: datetime | None
    end: datetime
    bucket: Literal["hour", "day", "week"]
    totals: Totals
    alerts_by_severity: list[Count]
    alerts_by_status: list[Count]
    events_over_time: list[TimePoint]
    alerts_over_time: list[SeverityPoint]
    top_source_ips: list[TopIp]
    top_rules: list[TopRule]
    recent_jobs: list[RecentJob]
    recent_high_alerts: list[AlertOut]
    data_range: DataRange


class EventListItem(BaseModel):
    id: int
    event_time: datetime
    ingested_at: datetime
    event_type: str
    source_ip: str | None
    username: str | None
    http_method: str | None
    path: str | None
    query: str | None
    http_status: int | None
    bytes_sent: int | None
    user_agent: str | None
    host: str | None
    severity: str | None
    message: str | None
    source_id: int
    source_name: str
    raw_line: str
    alert_count: int
    max_alert_severity: str | None


class EventPage(BaseModel):
    items: list[EventListItem]
    next_cursor: str | None
    count: int | None = None
    count_capped: bool = False


class LinkedAlert(BaseModel):
    id: int
    rule_id: str
    title: str
    severity: str
    status: str
    indicator: str | None


class EventDetail(EventListItem):
    referrer: str | None
    http_version: str | None
    attributes: dict[str, Any]
    file_id: int
    filename: str
    line_number: int
    job_id: int
    alerts: list[LinkedAlert]
